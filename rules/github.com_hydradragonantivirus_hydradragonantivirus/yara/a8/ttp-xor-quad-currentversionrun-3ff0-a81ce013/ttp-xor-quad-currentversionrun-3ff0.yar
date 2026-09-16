rule TTP_XOR_QUAD_CurrentVersionRun_3ff0 {
  strings:
    $key_3ff0 = { 6c 9f [2] 48 91 [2] 63 bd [2] 4d 9f [2] 59 84 [2] 56 9e [2] 48 83 [2] 4a 82 [2] 51 84 [2] 4d 83 [2] 51 ac }

  condition:
    any of them
}