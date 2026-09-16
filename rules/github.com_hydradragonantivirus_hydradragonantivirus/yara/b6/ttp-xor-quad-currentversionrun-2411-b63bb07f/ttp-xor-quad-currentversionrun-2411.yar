rule TTP_XOR_QUAD_CurrentVersionRun_2411 {
  strings:
    $key_2411 = { 77 7e [2] 53 70 [2] 78 5c [2] 56 7e [2] 42 65 [2] 4d 7f [2] 53 62 [2] 51 63 [2] 4a 65 [2] 56 62 [2] 4a 4d }

  condition:
    any of them
}