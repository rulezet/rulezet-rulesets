rule TTP_XOR_QUAD_CurrentVersionRun_2b52 {
  strings:
    $key_2b52 = { 78 3d [2] 5c 33 [2] 77 1f [2] 59 3d [2] 4d 26 [2] 42 3c [2] 5c 21 [2] 5e 20 [2] 45 26 [2] 59 21 [2] 45 0e }

  condition:
    any of them
}