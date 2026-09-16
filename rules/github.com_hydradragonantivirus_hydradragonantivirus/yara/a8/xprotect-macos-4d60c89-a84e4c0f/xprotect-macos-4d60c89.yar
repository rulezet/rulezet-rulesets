rule XProtect_MACOS_4d60c89 {
  meta:
    description = "MACOS.4d60c89"

  strings:
    $a1 = "#!"

    $b1 = "_pkg_install_"

    $b2 = "publisher_id"

    $b3 = "page_id"

    $b4 = "PAGE_ID"

    $b5 = "productVersion"

    $b6 = "com.apple.metadata:kMDItemWhereFroms"

    $b7 = "\\\"event\\\": \\\"success\\\""

    $b8 = "\\\"event\\\": \\\"start\\\""

    $c1 = "system_profiler SPHardwareDataType | awk"

    $c2 = "launchctl load -w"

    $c3 = "ioreg -ad2 -c IOPlatformExpertDevice"

    $c4 = "sw_vers -product"

    $c5 = "defaults write \"$plistLA\""

    $c6 = "sudo curl"

    $c7 = "osversion"

    $c8 = "WhereFrom"

    $c9 = "whereFrom"

    $c10 = "StartInterval"

    $c11 = "RunAtLoad"

  condition:
    filesize < 10KB and $a1 at 0 and 4 of ($b*) and (6 of ($c*))
}