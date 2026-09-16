rule TTP_XOR_QUAD_CurrentVersionRun_1952 {
  strings:
    $key_1952 = { 4a 3d [2] 6e 33 [2] 45 1f [2] 6b 3d [2] 7f 26 [2] 70 3c [2] 6e 21 [2] 6c 20 [2] 77 26 [2] 6b 21 [2] 77 0e }

  condition:
    any of them
}