rule sig_20161207_d3ef2f071b95cfefab8139f65d362f32 {
  meta:
    description = "datamaliciousorder - file 20161207_d3ef2f071b95cfefab8139f65d362f32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89a0b8c96b63ae0fb6c275e487ce03cacce8a0b0d09d92fa0ea9776be11d8e6a"

  strings:
    $s1 = " = new Date();vAHv3[\"setUTCFullYear\"](\"2003\");if (vAHv3.getUTCFullYear().toString(10) == \"2003\") {var vINz5 = vCFd0.split(" ascii
    $s2 = "var vOw9 = new Function(\"vCFd0\", '{return vCFd0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDe7 = new Function(\"vCFd" ascii
    $s3 = "var vOw9 = new Function(\"vCFd0\", '{return vCFd0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDe7 = new Function(\"vCFd" ascii
    $s4 = "); return vINz5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}