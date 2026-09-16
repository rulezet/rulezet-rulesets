rule SUSP_LoadLibraryA_mutation_rot13 {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
    date        = "2024-01-25"
    version     = "1.0"
    DaysofYARA  = "25/100"

  strings:
    $LoadLibraryA_rot13 = "YbnqYvoenelN" nocase ascii wide

  condition:
    all of them
}