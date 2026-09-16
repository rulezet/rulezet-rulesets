rule macos_adload_python_dropper {
  meta:
    description = "MACOS.ADLOAD"

  strings:
    $shebang = "#!"

    $iokit_1 = "IOKit"
    $iokit_2 = "IOServiceGetMatchingService"
    $iokit_3 = "IOServiceMatching"
    $iokit_4 = "IORegistryEntryCreateCFProperty"
    $iokit_5 = "IOPlatformExpertDevice"

    $method_1 = "rmtree"
    $method_2 = "load_source"
    $method_3 = "encryptText"
    $method_4 = "decryptText"
    $method_5 = "encryptList"
    $method_6 = "decryptList"
    $method_7 = "check_call"
    $method_8 = "endswith"
    $method_9 = "mac_ver"

    $string_1  = "chmod"
    $string_2  = "/dev/null"
    $string_3  = "key"
    $string_4  = "commands"
    $string_5  = "uuid"
    $string_6  = "machineID"
    $string_7  = "open"
    $string_8  = "sessionID"
    $string_9  = "appName"
    $string_10 = "curl"
    $string_11 = "/tmp"
    $string_12 = "unzip"
    $string_13 = "/Volumes"
    $string_14 = "--args"

  condition:
    $shebang at 0 and (4 of ($iokit_*)) and (7 of ($method_*)) and (10 of ($string_*))
}