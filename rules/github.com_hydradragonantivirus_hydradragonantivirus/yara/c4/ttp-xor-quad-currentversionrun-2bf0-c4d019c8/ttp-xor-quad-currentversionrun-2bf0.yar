rule TTP_XOR_QUAD_CurrentVersionRun_2bf0 {
  strings:
    $key_2bf0 = { 78 9f [2] 5c 91 [2] 77 bd [2] 59 9f [2] 4d 84 [2] 42 9e [2] 5c 83 [2] 5e 82 [2] 45 84 [2] 59 83 [2] 45 ac }

  condition:
    any of them
}