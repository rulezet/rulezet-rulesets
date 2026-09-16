rule TTP_XOR_QUAD_CurrentVersionRun_1ff0 {
  strings:
    $key_1ff0 = { 4c 9f [2] 68 91 [2] 43 bd [2] 6d 9f [2] 79 84 [2] 76 9e [2] 68 83 [2] 6a 82 [2] 71 84 [2] 6d 83 [2] 71 ac }

  condition:
    any of them
}