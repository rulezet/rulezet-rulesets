rule TTP_XOR_WriteProcessMemory_9cae {
  strings:
    $key_9cae = { cb dc [2] f9 fe [2] ff cb [2] d1 cb [2] ee d7 }

  condition:
    any of them
}