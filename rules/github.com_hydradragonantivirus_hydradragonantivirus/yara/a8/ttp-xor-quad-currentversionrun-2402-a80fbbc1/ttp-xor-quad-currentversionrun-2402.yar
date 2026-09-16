rule TTP_XOR_QUAD_CurrentVersionRun_2402 {
  strings:
    $key_2402 = { 77 6d [2] 53 63 [2] 78 4f [2] 56 6d [2] 42 76 [2] 4d 6c [2] 53 71 [2] 51 70 [2] 4a 76 [2] 56 71 [2] 4a 5e }

  condition:
    any of them
}