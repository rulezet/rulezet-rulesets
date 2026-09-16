rule SUSP_ntdlldll_mutation_rot13 {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of ntdll.dll which can be used for syscalls"
    date        = "2024-01-23"
    version     = "1.0"
    DaysofYARA  = "24/100"

  strings:
    $ntdlldll_rot13 = "agqyy.qyy" ascii wide nocase

  condition:
    all of them
}