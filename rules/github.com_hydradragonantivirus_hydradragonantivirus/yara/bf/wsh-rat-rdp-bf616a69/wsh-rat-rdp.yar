rule wsh_rat_rdp {
  meta:
    author      = "jeFF0Falltrades"
    ref         = "https://cofense.com/houdini-worm-transformed-new-phishing-attack"
    description = "Alerts on the WSH RAT .NET RDP module"

  strings:
    $str_0 = "GET /open-rdp|" wide ascii nocase
    $str_1 = "WSHRat Plugin" wide ascii nocase
    $str_2 = "Debug\\RDP.pdb" wide ascii nocase
    $str_3 = "TakeShoot" wide ascii nocase
    $str_4 = "CompressJPEG" wide ascii nocase

  condition:
    3 of them
}