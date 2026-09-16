rule TTP_XOR_QUAD_CurrentVersionRun_0b8f {
  strings:
    $key_0b8f = { 58 e0 [2] 7c ee [2] 57 c2 [2] 79 e0 [2] 6d fb [2] 62 e1 [2] 7c fc [2] 7e fd [2] 65 fb [2] 79 fc [2] 65 d3 }

  condition:
    any of them
}