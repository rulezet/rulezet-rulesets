rule TTP_XOR_QUAD_CurrentVersionRun_3222 {
  strings:
    $key_3222 = { 61 4d [2] 45 43 [2] 6e 6f [2] 40 4d [2] 54 56 [2] 5b 4c [2] 45 51 [2] 47 50 [2] 5c 56 [2] 40 51 [2] 5c 7e }

  condition:
    any of them
}