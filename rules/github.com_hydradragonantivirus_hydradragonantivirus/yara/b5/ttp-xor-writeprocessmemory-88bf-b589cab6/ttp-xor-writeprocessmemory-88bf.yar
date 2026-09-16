rule TTP_XOR_WriteProcessMemory_88bf {
  strings:
    $key_88bf = { df cd [2] ed ef [2] eb da [2] c5 da [2] fa c6 }

  condition:
    any of them
}