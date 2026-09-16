rule XProtect_MACOS_889c9e6 {
  meta:
    description = "MACOS.889c9e6"

  strings:
    $a  = "#!/usr/bin/env bash\n"
    $b1 = "/Contents/MacOS/Google Chrome\" --remote-debugging-port=19234"
    $b2 = "/Contents/MacOS/Brave Browser\" --remote-debugging-port=19384"
    $b3 = "/Contents/MacOS/Microsoft Edge\" --remote-debugging-port=19264"
    $b4 = "/Contents/MacOS/firefox\" --start-debugger-server ws:19240"
    $b5 = "/Contents/MacOS/Opera\" --remote-debugging-port=19238"
    $b6 = "/Contents/MacOS/360Chrome\" --remote-debugging-port=19268"
    $b7 = "/Contents/MacOS/Yandex\" --remote-debugging-port=19236"
    $b8 = "/Contents/MacOS/Chromium\" --remote-debugging-port=19236"
    $b9 = "/Library/Containers/Safari/run.py"

  condition:
    $a at 0 and any of ($b*) and filesize < 200
}