import "pe"
rule INFO_PE_Imports_NDIS_NetworkInterface {
  meta:
    author      = "Greg Lesnewich"
    date        = "2024-01-20"
    version     = "1.0"
    description = "track executable files that import NDIS which is a legitimate driver for the network interface controller."
    DaysofYARA  = "20/100"

  condition:
    for any imp in pe.import_details: (
      imp.library_name == "NDIS.SYS"
    )
}