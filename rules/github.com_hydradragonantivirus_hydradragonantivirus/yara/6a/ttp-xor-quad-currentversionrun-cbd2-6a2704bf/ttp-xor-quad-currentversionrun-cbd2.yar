rule TTP_XOR_QUAD_CurrentVersionRun_cbd2 {
  strings:
    $key_cbd2 = { 98 bd [2] bc b3 [2] 97 9f [2] b9 bd [2] ad a6 [2] a2 bc [2] bc a1 [2] be a0 [2] a5 a6 [2] b9 a1 [2] a5 8e }

  condition:
    any of them
}