rule TTP_XOR_QUAD_CurrentVersionRun_cc98 {
  strings:
    $key_cc98 = { 9f f7 [2] bb f9 [2] 90 d5 [2] be f7 [2] aa ec [2] a5 f6 [2] bb eb [2] b9 ea [2] a2 ec [2] be eb [2] a2 c4 }

  condition:
    any of them
}