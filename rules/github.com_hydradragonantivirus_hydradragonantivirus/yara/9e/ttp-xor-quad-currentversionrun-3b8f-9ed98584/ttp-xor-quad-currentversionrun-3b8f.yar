rule TTP_XOR_QUAD_CurrentVersionRun_3b8f {
  strings:
    $key_3b8f = { 68 e0 [2] 4c ee [2] 67 c2 [2] 49 e0 [2] 5d fb [2] 52 e1 [2] 4c fc [2] 4e fd [2] 55 fb [2] 49 fc [2] 55 d3 }

  condition:
    any of them
}