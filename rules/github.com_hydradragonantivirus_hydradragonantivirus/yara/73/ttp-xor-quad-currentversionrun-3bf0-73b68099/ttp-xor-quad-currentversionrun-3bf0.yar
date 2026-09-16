rule TTP_XOR_QUAD_CurrentVersionRun_3bf0 {
  strings:
    $key_3bf0 = { 68 9f [2] 4c 91 [2] 67 bd [2] 49 9f [2] 5d 84 [2] 52 9e [2] 4c 83 [2] 4e 82 [2] 55 84 [2] 49 83 [2] 55 ac }

  condition:
    any of them
}