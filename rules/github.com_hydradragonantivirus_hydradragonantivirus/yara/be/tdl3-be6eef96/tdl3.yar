rule tdl3
{
        meta:
        null_string = 1

        strings:
        $1 = "\\\\?\\globalroot\\"
        $2 = ".ini" 

        condition:
        all of them
        }