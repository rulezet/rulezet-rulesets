rule TTP_XOR_QUAD_CurrentVersionRun_c2f6 {
  strings:
    $key_c2f6 = { 91 99 [2] b5 97 [2] 9e bb [2] b0 99 [2] a4 82 [2] ab 98 [2] b5 85 [2] b7 84 [2] ac 82 [2] b0 85 [2] ac aa }

  condition:
    any of them
}