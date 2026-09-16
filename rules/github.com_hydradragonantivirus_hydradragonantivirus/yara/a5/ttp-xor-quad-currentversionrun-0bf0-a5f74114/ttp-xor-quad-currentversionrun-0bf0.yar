rule TTP_XOR_QUAD_CurrentVersionRun_0bf0 {
  strings:
    $key_0bf0 = { 58 9f [2] 7c 91 [2] 57 bd [2] 79 9f [2] 6d 84 [2] 62 9e [2] 7c 83 [2] 7e 82 [2] 65 84 [2] 79 83 [2] 65 ac }

  condition:
    any of them
}