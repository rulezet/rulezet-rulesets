rule TTP_XOR_QUAD_CurrentVersionRun_0ff0 {
  strings:
    $key_0ff0 = { 5c 9f [2] 78 91 [2] 53 bd [2] 7d 9f [2] 69 84 [2] 66 9e [2] 78 83 [2] 7a 82 [2] 61 84 [2] 7d 83 [2] 61 ac }

  condition:
    any of them
}