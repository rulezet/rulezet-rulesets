rule TTP_XOR_QUAD_CurrentVersionRun_d810 {
  strings:
    $key_d810 = { 8b 7f [2] af 71 [2] 84 5d [2] aa 7f [2] be 64 [2] b1 7e [2] af 63 [2] ad 62 [2] b6 64 [2] aa 63 [2] b6 4c }

  condition:
    any of them
}