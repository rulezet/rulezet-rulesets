rule GIFCloaked_Webshell {
  meta:
    description = "Looks like a webshell cloaked as GIF"
    author      = "Florian Roth"
    hash        = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
    score       = 50

  strings:
    $magic = "GIF8"  
    $s0    = "input type"
    $s1    = "<%eval request"
    $s2    = "<%eval(Request.Item["
    $s3    = "LANGUAGE='VBScript'"

  condition:
    ($magic at 0) and (1 of ($s*))
}