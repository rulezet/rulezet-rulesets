import "pe"
rule SUSP_PE_HashLike_DLL_Name_MD5 {
  meta:
    author      = "Greg Lesnewich"
    description = "looking for hashes in weird places"
    date        = "2024-02-05"
    version     = "1.0"
    DaysOfYara  = "36/100"

  condition:
    pe.dll_name matches /[a-z0-9A-Z]{32}.dll/
}