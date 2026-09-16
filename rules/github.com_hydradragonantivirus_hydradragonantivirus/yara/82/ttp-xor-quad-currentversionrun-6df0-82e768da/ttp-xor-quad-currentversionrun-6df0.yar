rule TTP_XOR_QUAD_CurrentVersionRun_6df0 {
  strings:
    $key_6df0 = { 3e 9f [2] 1a 91 [2] 31 bd [2] 1f 9f [2] 0b 84 [2] 04 9e [2] 1a 83 [2] 18 82 [2] 03 84 [2] 1f 83 [2] 03 ac }

  condition:
    any of them
}