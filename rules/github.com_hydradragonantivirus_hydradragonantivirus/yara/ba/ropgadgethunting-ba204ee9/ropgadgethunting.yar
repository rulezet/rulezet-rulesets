rule RopGadgetHunting
{
    meta:
        author = "Daniel Mayer (daniel@stairwell.com)"
        description = "An experimental rule for detecting ROP gadget hunting"
        version = "1.0"
        date = "2023-02-24"
        reference1="https://github.com/LloydLabs/ntqueueapcthreadex-ntdll-gadget-injection"
    strings:
                $flag_hunt = {      
            25 20 00 00 20              3D 20 00 00 20              }
                $ret_cmp = { 
            80 [1-2] C3                 } 
    condition:
        uint16(0) == 0x5A4D and all of them
}