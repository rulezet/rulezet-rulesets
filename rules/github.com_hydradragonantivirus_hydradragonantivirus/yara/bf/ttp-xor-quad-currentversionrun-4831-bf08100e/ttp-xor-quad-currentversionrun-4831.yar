rule TTP_XOR_QUAD_CurrentVersionRun_4831 {
  strings:
    $key_4831 = { 1b 5e [2] 3f 50 [2] 14 7c [2] 3a 5e [2] 2e 45 [2] 21 5f [2] 3f 42 [2] 3d 43 [2] 26 45 [2] 3a 42 [2] 26 6d }

  condition:
    any of them
}