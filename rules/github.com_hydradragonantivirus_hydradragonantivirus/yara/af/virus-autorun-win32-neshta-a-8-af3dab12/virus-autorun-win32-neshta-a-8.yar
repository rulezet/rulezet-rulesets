rule Virus_Autorun_Win32_Neshta_A_8 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad43d574046ba17f5ba1946c8fa498d10554eca4f961b9c5d1a465a1855e12dc"

  strings:
    $x1  = "<Execute>g__LogDropCommand|3_0" fullword ascii
    $s2  = "return MigrationsBundle.Execute(" fullword wide
    $s3  = "CGenerates a SQL script from the DbContext. Bypasses any migrations." fullword ascii
    $s4  = "The target framework." fullword ascii
    $s5  = "!The target runtime to bundle for." fullword ascii
    $s6  = "(Entity Framework Core Command-line Tools" fullword ascii
    $s7  = "Entity Framework Core Command-line Tools" fullword wide
    $s8  = "Use \"{0} [command] --help\" for more information about a command." fullword wide
    $s9  = " Commands to manage the database." fullword ascii
    $s10 = "^The target migration. If '0', all migrations will be reverted. Defaults to the last migration." fullword ascii
    $s11 = "5The target migration. Defaults to the last migration." fullword ascii
    $s12 = "9The root namespace. Defaults to the target assembly name." fullword ascii
    $s13 = "#Commands to manage DbContext types." fullword ascii
    $s14 = "on of Entity Framework Core lower than 5.0.0 or when an error occurrs while accessing the database." fullword ascii
    $s15 = "-Creates an executable to update the database." fullword ascii
    $s16 = "8The working directory of the tool invoking this command." fullword ascii
    $s17 = "@This feature requires Entity Framework Core {version} or higher." fullword ascii
    $s18 = "Commands to manage migrations." fullword ascii
    $s19 = "&The path of executable file to create." fullword ascii
    $s20 = "<Command>b__78_0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}