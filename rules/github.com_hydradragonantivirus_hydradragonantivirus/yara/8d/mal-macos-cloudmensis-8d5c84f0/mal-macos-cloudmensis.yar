rule mal_macos_cloudmensis {
  meta:
    description = "Identify the CloudMensis/SNOWDRIFT malware"
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.02.21"
    reference   = "https://www.welivesecurity.com/2022/07/19/i-see-what-you-did-there-look-cloudmensis-macos-spyware/"
    sample      = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
    DaysofYARA  = "52/100"

  strings:
    $ = "SearchAndMoveFS:removable:"
    $ = "SavePetConfigData"
    $ = "csrutil status | grep disabled"
    $ = "CheckScreenSaverState"

  condition:
    all of them

}