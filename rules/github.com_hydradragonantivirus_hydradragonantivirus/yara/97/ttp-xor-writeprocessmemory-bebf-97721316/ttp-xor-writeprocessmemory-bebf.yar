rule TTP_XOR_WriteProcessMemory_bebf {
  strings:
    $key_bebf = { e9 cd [2] db ef [2] dd da [2] f3 da [2] cc c6 }

  condition:
    any of them
}