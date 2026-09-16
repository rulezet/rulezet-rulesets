rule TTP_XOR_QUAD_CurrentVersionRun_4ff0 {
  strings:
    $key_4ff0 = { 1c 9f [2] 38 91 [2] 13 bd [2] 3d 9f [2] 29 84 [2] 26 9e [2] 38 83 [2] 3a 82 [2] 21 84 [2] 3d 83 [2] 21 ac }

  condition:
    any of them
}