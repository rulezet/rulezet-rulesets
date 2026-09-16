rule TTP_XOR_QUAD_CurrentVersionRun_117c {
  strings:
    $key_117c = { 42 13 [2] 66 1d [2] 4d 31 [2] 63 13 [2] 77 08 [2] 78 12 [2] 66 0f [2] 64 0e [2] 7f 08 [2] 63 0f [2] 7f 20 }

  condition:
    any of them
}