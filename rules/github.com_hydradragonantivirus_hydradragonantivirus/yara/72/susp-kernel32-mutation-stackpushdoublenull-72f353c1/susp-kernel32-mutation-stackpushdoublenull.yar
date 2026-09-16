rule SUSP_kernel32_mutation_stackpushdoublenull {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of kernel32 which can be used for lots of evil things"
    date        = "2024-01-24"
    version     = "1.0"
    DaysofYARA  = "24/100"

  strings:
    $kernel32_stackpushdoublenull = "hel32\x00\x00hkern"

  condition:
    all of them
}