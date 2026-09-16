rule Linux_ARM_Mirai_Weirdo_Variant_2022_03_16 {
  meta:
    description = "Detects new ARM Mirai variant"
    author      = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
    date        = "2022-03-16"
    hash1       = "4e5aced627646ff9425802a256c80d6c8971c3daa4c329b83d9e96d492a8cecd"

  strings:
    $connection1 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" wide ascii
    $connection2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" wide ascii
    $weird1      = "MELTEDNINJAREALZ" wide ascii
    $weird2      = "NiGGeRD0nks69" wide ascii
    $weird3      = "freecookiex86" wide ascii
    $weird4      = "NiGGeRD0nks69" wide ascii
    $weird5      = "1337SoraLOADER" wide ascii
    $weird6      = "SEXSLAVE1337" wide ascii
    $weird7      = "SoraBeReppin1337" wide ascii
    $weird8      = "ayyyGangShit" wide ascii
    $weird9      = "stresser.pw" wide ascii
    $pat1        = "/dev/null" wide ascii
    $pat2        = "/root/" wide ascii
    $pat3        = "/var/" wide ascii
    $pat4        = "/sys/devices/system/cpu" wide ascii
    $pat5        = "/proc/cpuinfo" wide ascii

  condition:
    uint16(0) == 0x457f and ((all of ($connection*)) and (4 or all of ($weird*)) and (3 or all of ($pat*)))
}