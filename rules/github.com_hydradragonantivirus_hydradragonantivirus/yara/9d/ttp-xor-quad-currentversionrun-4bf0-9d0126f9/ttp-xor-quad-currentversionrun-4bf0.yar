rule TTP_XOR_QUAD_CurrentVersionRun_4bf0 {
  strings:
    $key_4bf0 = { 18 9f [2] 3c 91 [2] 17 bd [2] 39 9f [2] 2d 84 [2] 22 9e [2] 3c 83 [2] 3e 82 [2] 25 84 [2] 39 83 [2] 25 ac }

  condition:
    any of them
}