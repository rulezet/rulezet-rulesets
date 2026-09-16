rule TTP_XOR_QUAD_CurrentVersionRun_7bf0 {
  strings:
    $key_7bf0 = { 28 9f [2] 0c 91 [2] 27 bd [2] 09 9f [2] 1d 84 [2] 12 9e [2] 0c 83 [2] 0e 82 [2] 15 84 [2] 09 83 [2] 15 ac }

  condition:
    any of them
}