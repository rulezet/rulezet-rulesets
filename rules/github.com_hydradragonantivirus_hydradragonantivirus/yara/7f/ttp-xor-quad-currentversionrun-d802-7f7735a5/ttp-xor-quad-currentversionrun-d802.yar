rule TTP_XOR_QUAD_CurrentVersionRun_d802 {
  strings:
    $key_d802 = { 8b 6d [2] af 63 [2] 84 4f [2] aa 6d [2] be 76 [2] b1 6c [2] af 71 [2] ad 70 [2] b6 76 [2] aa 71 [2] b6 5e }

  condition:
    any of them
}