import "pe"
rule INFO_PE_Imports_HardwareAbstractionLayer {
  meta:
    author      = "Greg Lesnewich"
    date        = "2024-01-20"
    version     = "1.0"
    description = "track executable files that import hardware abstraction layer (HAL) components"
    DaysofYARA  = "20/100"

  condition:
    for any s in ("hal.dll", "halacpi.dll", "halmacpi.dll"): (
      for any imp in pe.import_details: (
        imp.library_name iequals s
      ))
}