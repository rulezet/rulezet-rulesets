rule TTP_XOR_WriteProcessMemory_abac {
  strings:
    $key_abac = { fc de [2] ce fc [2] c8 c9 [2] e6 c9 [2] d9 d5 }

  condition:
    any of them
}