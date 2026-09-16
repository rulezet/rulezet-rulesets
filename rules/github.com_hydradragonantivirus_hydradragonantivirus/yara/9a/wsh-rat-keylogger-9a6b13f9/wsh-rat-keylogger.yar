rule wsh_rat_keylogger {
  meta:
    author      = "jeFF0Falltrades"
    ref         = "https://cofense.com/houdini-worm-transformed-new-phishing-attack"
    description = "Alerts on the WSH RAT .NET keylogger module"

  strings:
    $str_0 = "Keylogger" wide ascii nocase
    $str_1 = "RunKeyloggerOffline" wide ascii nocase
    $str_2 = "saveKeyLog" wide ascii nocase
    $str_3 = "sendKeyLog" wide ascii nocase
    $str_4 = "/open-keylogger" wide ascii nocase
    $str_5 = "wshlogs" wide ascii nocase
    $str_6 = "WSHRat Plugin" wide ascii nocase
    $str_7 = "Debug\\Keylogger.pdb" wide ascii nocase

  condition:
    3 of them
}