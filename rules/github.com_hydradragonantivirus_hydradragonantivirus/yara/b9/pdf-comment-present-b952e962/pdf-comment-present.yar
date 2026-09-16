rule pdf_comment_present
{
    meta:
        author = "kyle eaton"
        date = "02/12/2024"
        day = "2/100"
    strings:
        $pdf = {25 50 44 46 2d}
    condition:
        $pdf at 0 and 
        uint8(9) != 0x31
}