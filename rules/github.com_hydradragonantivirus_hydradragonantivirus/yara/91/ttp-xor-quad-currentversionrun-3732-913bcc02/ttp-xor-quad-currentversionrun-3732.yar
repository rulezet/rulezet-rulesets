rule TTP_XOR_QUAD_CurrentVersionRun_3732 {
  strings:
    $key_3732 = { 64 5d [2] 40 53 [2] 6b 7f [2] 45 5d [2] 51 46 [2] 5e 5c [2] 40 41 [2] 42 40 [2] 59 46 [2] 45 41 [2] 59 6e }

  condition:
    any of them
}