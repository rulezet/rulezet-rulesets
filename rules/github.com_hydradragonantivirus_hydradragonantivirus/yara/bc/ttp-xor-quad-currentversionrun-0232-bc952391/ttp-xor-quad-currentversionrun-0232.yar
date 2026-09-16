rule TTP_XOR_QUAD_CurrentVersionRun_0232 {
  strings:
    $key_0232 = { 51 5d [2] 75 53 [2] 5e 7f [2] 70 5d [2] 64 46 [2] 6b 5c [2] 75 41 [2] 77 40 [2] 6c 46 [2] 70 41 [2] 6c 6e }

  condition:
    any of them
}