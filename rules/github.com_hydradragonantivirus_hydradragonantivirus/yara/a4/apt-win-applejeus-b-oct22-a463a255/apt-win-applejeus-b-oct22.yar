rule apt_win_applejeus_b_oct22: Lazarus {
  meta:
    author          = "threatintel@volexity.com"
    date            = "2022-11-03"
    description     = "Detected AppleJeus unpacked samples."
    hash1           = "9352625b3e6a3c998e328e11ad43efb5602fe669aed9c9388af5f55fadfedc78"
    memory_suitable = 1
    license         = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

  strings:
    $key1 = "AppX7y4nbzq37zn4ks9k7amqjywdat7d"
    $key2 = "Gd2n5frvG2eZ1KOe"

    $str1 = "Windows %d(%d)-%s"
    $str2 = "&act=check"

  condition:
    (
      any of ($key*) and
      1 of ($str*)
    ) or
    all of ($str*)
}