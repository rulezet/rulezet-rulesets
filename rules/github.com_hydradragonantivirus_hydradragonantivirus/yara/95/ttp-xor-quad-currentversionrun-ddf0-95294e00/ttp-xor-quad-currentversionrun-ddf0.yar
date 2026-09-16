rule TTP_XOR_QUAD_CurrentVersionRun_ddf0 {
  strings:
    $key_ddf0 = { 8e 9f [2] aa 91 [2] 81 bd [2] af 9f [2] bb 84 [2] b4 9e [2] aa 83 [2] a8 82 [2] b3 84 [2] af 83 [2] b3 ac }

  condition:
    any of them
}