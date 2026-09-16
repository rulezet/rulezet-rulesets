rule OpenJPEG_dwt_norms_real__flt32___32_lil_148_ {
  strings:
    $a0 = { 00 00 80 3f 1f 85 fb 3f fc a9 85 40 b0 72 06 41 33 33 87 41 29 5c 07 42 48 61 87 42 cd 4c 07 43 cd 4c 87 43 9a 39 07 44 73 68 01 40 c7 4b 7f 40 14 ae 05 41 ec 51 88 41 7b 14 09 42 8f 42 89 42 cd 4c 09 43 cd 4c 89 43 00 40 09 44 73 68 01 40 c7 4b 7f 40 14 ae 05 41 ec 51 88 41 7b 14 09 42 8f 42 89 42 cd 4c 09 43 cd 4c 89 43 00 40 09 44 b8 1e 05 40 29 5c 77 40 79 e9 04 41 a4 70 89 41 0a d7 0a 42 14 2e 8b 42 cd 4c 0b 43 cd 4c 8b 43 cd 4c 0b 44 }

  condition:
    $a0
}