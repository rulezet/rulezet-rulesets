rule TTP_XOR_QUAD_CurrentVersionRun_b9b1 {
  strings:
    $key_b9b1 = { ea de [2] ce d0 [2] e5 fc [2] cb de [2] df c5 [2] d0 df [2] ce c2 [2] cc c3 [2] d7 c5 [2] cb c2 [2] d7 ed }

  condition:
    any of them
}