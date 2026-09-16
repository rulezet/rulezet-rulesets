rule TTP_XOR_QUAD_CurrentVersionRun_eaf0 {
  strings:
    $key_eaf0 = { b9 9f [2] 9d 91 [2] b6 bd [2] 98 9f [2] 8c 84 [2] 83 9e [2] 9d 83 [2] 9f 82 [2] 84 84 [2] 98 83 [2] 84 ac }

  condition:
    any of them
}